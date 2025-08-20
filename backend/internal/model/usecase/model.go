package usecase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/schema"
	"github.com/gofiber/fiber/v2/log"
	"github.com/google/uuid"

	"github.com/chaitin/MonkeyCode/backend/config"
	"github.com/chaitin/MonkeyCode/backend/consts"
	"github.com/chaitin/MonkeyCode/backend/db"
	"github.com/chaitin/MonkeyCode/backend/db/model"
	"github.com/chaitin/MonkeyCode/backend/domain"
	"github.com/chaitin/MonkeyCode/backend/ent/types"
	"github.com/chaitin/MonkeyCode/backend/pkg/cvt"
	"github.com/chaitin/MonkeyCode/backend/pkg/request"
)

type ModelUsecase struct {
	logger *slog.Logger
	repo   domain.ModelRepo
	cfg    *config.Config
	client *http.Client
}

func NewModelUsecase(
	logger *slog.Logger,
	repo domain.ModelRepo,
	cfg *config.Config,
) domain.ModelUsecase {
	//取读并启用代理
	proxyFunc := func() func(*http.Request) (*url.URL, error) {
		proxy := strings.TrimSpace(os.Getenv("HTTP_PROXY"))

		if proxy != "" {
			proxyURL, err := url.Parse(proxy)
			if err != nil {
				log.Error("failed to parse proxy URL ", proxy, err)
				return nil
			}
			result := http.ProxyURL(proxyURL)
			if result == nil {
				log.Error("failed to create proxy URL ", proxy)
			} else {
				log.Info("using proxy: ", proxyURL.String())
			}

			return result
		} else {
			log.Info("no proxy configured")
			return nil
		}
	}

	client := &http.Client{
		Timeout: time.Second * 30,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			MaxConnsPerHost:     100,
			IdleConnTimeout:     time.Second * 30,
			Proxy:               proxyFunc(),
		},
	}
	return &ModelUsecase{repo: repo, cfg: cfg, logger: logger, client: client}
}

func (m *ModelUsecase) Check(ctx context.Context, req *domain.CheckModelReq) (*domain.Model, error) {
	if req.Type == consts.ModelTypeEmbedding || req.Type == consts.ModelTypeReranker {
		url := req.APIBase
		reqBody := map[string]any{}
		if req.Type == consts.ModelTypeEmbedding {
			reqBody = map[string]any{
				"model":           req.ModelName,
				"input":           "MonkeyCode 是一个基于大模型的代码生成器，它可以根据用户的需求生成代码。",
				"encoding_format": "float",
			}
			url = req.APIBase + "/embeddings"
		}
		if req.Type == consts.ModelTypeReranker {
			reqBody = map[string]any{
				"model": req.ModelName,
				"documents": []string{
					"MonkeyCode 是一个基于大模型的代码生成器，它可以根据用户的需求生成代码。",
					"MonkeyCode 是一个基于大模型的代码生成器，它可以根据用户的需求生成代码。",
					"MonkeyCode 是一个基于大模型的代码生成器，它可以根据用户的需求生成代码。",
				},
				"query": "MonkeyCode",
			}
			url = req.APIBase + "/rerank"
		}
		body, err := json.Marshal(reqBody)
		if err != nil {
			return nil, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", req.APIKey))
		request.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("request failed: %s", resp.Status)
		}
		return &domain.Model{}, nil
	}
	config := &openai.ChatModelConfig{
		APIKey:  req.APIKey,
		BaseURL: req.APIBase,
		Model:   string(req.ModelName),
	}
	// for azure openai
	if req.Provider == consts.ModelProviderAzureOpenAI {
		config.ByAzure = true
		config.APIVersion = req.APIVersion
		if config.APIVersion == "" {
			config.APIVersion = "2024-10-21"
		}
	}
	// 阿里云百炼模型支持流式和思考功能
	if req.Provider == consts.ModelProviderBaiLian {
		config.ExtraFields = map[string]any{
			"stream":          true,
			"enable_thinking": true,
		}
	}
	if req.APIHeader != "" {
		client := getHttpClientWithAPIHeaderMap(req.APIHeader)
		if client != nil {
			config.HTTPClient = client
		}
	}
	chatModel, err := openai.NewChatModel(ctx, config)
	if err != nil {
		return nil, err
	}
	// 阿里云百炼模型(不支持 翻译/OCR 模型的添加)
	if req.Provider == consts.ModelProviderBaiLian {
		msgs := []*schema.Message{
			schema.SystemMessage("You are a helpful assistant."),
			schema.UserMessage("hi"),
		}
		stream, err := chatModel.Stream(ctx, msgs)
		if err != nil {
			return nil, err
		}
		var content string
		for {
			msg, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					break
				}
				return nil, err
			}
			if msg.Content != "" {
				content += msg.Content
			}
		}

		if content == "" {
			return nil, fmt.Errorf("generate failed")
		}
	} else {
		resp, err := chatModel.Generate(ctx, []*schema.Message{
			schema.SystemMessage("You are a helpful assistant."),
			schema.UserMessage("hi"),
		})
		if err != nil {
			return nil, err
		}

		content := resp.Content
		if content == "" {
			return nil, fmt.Errorf("generate failed")
		}
	}
	return &domain.Model{
		ModelType: req.Type,
		Provider:  req.Provider,
		ModelName: req.ModelName,
		APIBase:   req.APIBase,
	}, nil
}

type headerTransport struct {
	headers map[string]string
	base    http.RoundTripper
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	return t.base.RoundTrip(req)
}

func getHttpClientWithAPIHeaderMap(header string) *http.Client {
	headerMap := request.GetHeaderMap(header)
	if len(headerMap) > 0 {
		// create http client with custom transport for headers
		client := &http.Client{
			Timeout: 0,
		}
		// Wrap the transport to add headers
		client.Transport = &headerTransport{
			headers: headerMap,
			base:    http.DefaultTransport,
		}
		return client
	}
	return nil
}

func (m *ModelUsecase) MyModelList(ctx context.Context, req *domain.MyModelListReq) ([]*domain.Model, error) {
	models, err := m.repo.MyModelList(ctx, req)
	if err != nil {
		return nil, err
	}
	ids := cvt.Iter(models, func(_ int, e *db.Model) uuid.UUID {
		return e.ID
	})
	usages, err := m.repo.ModelUsage(ctx, ids)
	if err != nil {
		return nil, err
	}
	return cvt.Iter(models, func(_ int, e *db.Model) *domain.Model {
		tmp := cvt.From(e, &domain.Model{}).From(e)
		if usage, ok := usages[e.ID]; ok {
			tmp.Input = usage.Input
			tmp.Output = usage.Output
		}
		return tmp
	}), nil
}

func (m *ModelUsecase) List(ctx context.Context) (*domain.AllModelResp, error) {
	return m.repo.List(ctx)
}

// Create implements domain.ModelUsecase.
func (m *ModelUsecase) Create(ctx context.Context, req *domain.CreateModelReq) (*domain.Model, error) {
	model, err := m.repo.Create(ctx, req)
	if err != nil {
		return nil, err
	}
	return cvt.From(model, &domain.Model{}), nil
}

// GetTokenUsage implements domain.ModelUsecase.
func (m *ModelUsecase) GetTokenUsage(ctx context.Context, modelType consts.ModelType) (*domain.ModelTokenUsageResp, error) {
	return m.repo.GetTokenUsage(ctx, modelType)
}

// Update implements domain.ModelUsecase.
func (m *ModelUsecase) Update(ctx context.Context, req *domain.UpdateModelReq) (*domain.Model, error) {
	m.logger.With("req", req).With("param", req.Param).DebugContext(ctx, "update model")
	model, err := m.repo.Update(ctx, req.ID, func(tx *db.Tx, old *db.Model, up *db.ModelUpdateOne) error {
		if req.ModelName != nil {
			up.SetModelName(*req.ModelName)
		}
		if req.Provider != nil {
			up.SetProvider(*req.Provider)
		}
		if req.APIBase != nil {
			up.SetAPIBase(*req.APIBase)
		}
		if req.APIKey != nil {
			up.SetAPIKey(*req.APIKey)
		}
		if req.APIVersion != nil {
			up.SetAPIVersion(*req.APIVersion)
		}
		if req.APIHeader != nil {
			up.SetAPIHeader(*req.APIHeader)
		}
		if req.ShowName != nil {
			up.SetShowName(*req.ShowName)
		}
		if req.Status != nil {
			if *req.Status == consts.ModelStatusActive {
				if err := tx.Model.Update().
					Where(model.ModelType(old.ModelType)).
					SetStatus(consts.ModelStatusInactive).
					Exec(ctx); err != nil {
					return err
				}
			}
			up.SetStatus(*req.Status)
		}
		if req.Param != nil {
			up.SetParameters(&types.ModelParam{
				R1Enabled:          req.Param.R1Enabled,
				MaxTokens:          req.Param.MaxTokens,
				ContextWindow:      req.Param.ContextWindow,
				SupprtImages:       req.Param.SupprtImages,
				SupportComputerUse: req.Param.SupportComputerUse,
				SupportPromptCache: req.Param.SupportPromptCache,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cvt.From(model, &domain.Model{}), nil
}

func (m *ModelUsecase) InitModel(ctx context.Context) error {
	m.logger.With("init_model", m.cfg.InitModel).Debug("init model")
	if m.cfg.InitModel.Name == "" {
		return nil
	}
	return m.repo.InitModel(ctx, m.cfg.InitModel.Name, m.cfg.InitModel.Key, m.cfg.InitModel.URL)
}

func (m *ModelUsecase) getQuery(req *domain.GetProviderModelListReq) request.Query {
	q := make(request.Query, 0)
	if req.Provider != consts.ModelProviderBaiZhiCloud && req.Provider != consts.ModelProviderSiliconFlow {
		return q
	}
	q["type"] = "text"
	q["sub_type"] = string(req.Type)
	if req.Type == consts.ModelTypeLLM {
		q["sub_type"] = "chat"
	}
	// 硅基流动不支持coder sub_type
	if req.Provider == consts.ModelProviderSiliconFlow && req.Type == consts.ModelTypeCoder {
		q["sub_type"] = "chat"
	}
	return q
}

func (m *ModelUsecase) GetProviderModelList(ctx context.Context, req *domain.GetProviderModelListReq) (*domain.GetProviderModelListResp, error) {
	switch req.Provider {
	case consts.ModelProviderAzureOpenAI,
		consts.ModelProviderVolcengine:
		return &domain.GetProviderModelListResp{
			Models: domain.ModelProviderBrandModelsList[req.Provider],
		}, nil
	case consts.ModelProviderOpenAI,
		consts.ModelProviderHunyuan,
		consts.ModelProviderMoonshot,
		consts.ModelProviderDeepSeek,
		consts.ModelProviderSiliconFlow,
		consts.ModelProviderBaiZhiCloud,
		consts.ModelProviderBaiLian:
		u, err := url.Parse(req.BaseURL)
		if err != nil {
			return nil, err
		}
		u.Path = path.Join(u.Path, "/models")
		client := request.NewClient(u.Scheme, u.Host, m.client.Timeout, request.WithClient(m.client))
		client.SetDebug(m.cfg.Debug)
		query := m.getQuery(req)
		resp, err := request.Get[domain.OpenAIResp](
			client, u.Path,
			request.WithHeader(
				request.Header{
					"Authorization": fmt.Sprintf("Bearer %s", req.APIKey),
				},
			),
			request.WithQuery(query),
		)
		if err != nil {
			return nil, err
		}

		return &domain.GetProviderModelListResp{
			Models: cvt.Iter(resp.Data, func(_ int, e *domain.OpenAIData) domain.ProviderModelListItem {
				return domain.ProviderModelListItem{
					Model: e.ID,
				}
			}),
		}, nil

	case consts.ModelProviderOllama:
		// get from ollama http://10.10.16.24:11434/api/tags
		u, err := url.Parse(req.BaseURL)
		if err != nil {
			return nil, err
		}
		u.Path = "/api/tags"
		client := request.NewClient(u.Scheme, u.Host, m.client.Timeout, request.WithClient(m.client))

		h := request.Header{}
		if req.APIHeader != "" {
			headers := request.GetHeaderMap(req.APIHeader)
			maps.Copy(h, headers)
		}

		return request.Get[domain.GetProviderModelListResp](client, u.Path, request.WithHeader(h))

	default:
		return nil, fmt.Errorf("invalid provider: %s", req.Provider)
	}
}

func (m *ModelUsecase) Delete(ctx context.Context, id string) error {
	return m.repo.Delete(ctx, id)
}
